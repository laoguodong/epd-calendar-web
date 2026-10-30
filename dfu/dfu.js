// Modern Nordic Secure DFU implementation for Web Bluetooth
// Supports single-bank & dual-bank Secure DFU on nRF52/nRF51

const DFU_SERVICE_UUID = "0000fe59-0000-1000-8000-00805f9b34fb";
const DFU_CONTROL_UUID = "8ec90001-f315-4f60-9fb8-838830daea50";
const DFU_PACKET_UUID = "8ec90002-f315-4f60-9fb8-838830daea50";
const DFU_BUTTONLESS_UUID = "8ec90003-f315-4f60-9fb8-838830daea50";

const OP_CREATE = 0x01;
const OP_SET_PRN = 0x02;
const OP_CRC = 0x03;
const OP_EXECUTE = 0x04;
const OP_SELECT = 0x06;
const OP_RESPONSE = 0x60;

const OBJECT_COMMAND = 0x01;
const OBJECT_DATA = 0x02;

const DFU_RESULTS = {
  0x00: "Invalid opcode",
  0x01: "Success",
  0x02: "Opcode not supported",
  0x03: "Invalid parameter",
  0x04: "Insufficient resources (空间或内存不足)",
  0x05: "Invalid object (固件签名或格式校验失败)",
  0x07: "Unsupported type",
  0x08: "Operation not permitted",
  0x0a: "Operation failed",
  0x0b: "Extended error"
};

const EXTENDED_ERRORS = {
  0x00: "No extended error code",
  0x01: "Invalid error code",
  0x02: "Wrong command format",
  0x03: "Command not supported",
  0x04: "Init command invalid",
  0x05: "Firmware version too low",
  0x06: "Hardware version mismatch",
  0x07: "SoftDevice mismatch",
  0x08: "Signature missing",
  0x09: "Hash type not supported",
  0x0a: "Hash calculation failed",
  0x0b: "Signature type unknown",
  0x0c: "Hash verification failed",
  0x0d: "Insufficient flash space for firmware"
};

// Precomputed CRC32 table
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC32_TABLE[i] = c >>> 0;
}

class NordicSecureDFU {
  constructor(logCallback, progressCallback) {
    this.log = logCallback || console.log;
    this.progress = progressCallback || (() => {});
    this.device = null;
    this.server = null;
    this.controlChar = null;
    this.packetChar = null;
    this.responseResolvers = [];
  }

  async selectDevice() {
    this.log("正在请求选择蓝牙设备...");
    const device = await navigator.bluetooth.requestDevice({
      acceptAllDevices: true,
      optionalServices: [
        DFU_SERVICE_UUID,
        0xfe59,
        "8ec90001-f315-4f60-9fb8-838830daea50",
        "8ec90002-f315-4f60-9fb8-838830daea50",
        "8ec90003-f315-4f60-9fb8-838830daea50",
        "62750001-d828-918d-fb46-b6c11c675aec",
        "00010203-0405-0607-0809-0a0b0c0d1912"
      ]
    });
    this.device = device;
    return device;
  }

  async connectAndCheckMode() {
    this.log(`连接设备: ${this.device.name || this.device.id}...`);
    this.server = await this.device.gatt.connect();

    let dfuService;
    try {
      dfuService = await this.server.getPrimaryService(DFU_SERVICE_UUID);
    } catch {
      try {
        dfuService = await this.server.getPrimaryService(0xfe59);
      } catch (e) {
        throw new Error("未找到 DFU 服务 (0xFE59)");
      }
    }

    const chars = await dfuService.getCharacteristics();
    const buttonless = chars.find(c => c.uuid.toLowerCase() === DFU_BUTTONLESS_UUID.toLowerCase());
    const control = chars.find(c => c.uuid.toLowerCase() === DFU_CONTROL_UUID.toLowerCase());
    const packet = chars.find(c => c.uuid.toLowerCase() === DFU_PACKET_UUID.toLowerCase());

    if (buttonless && !control) {
      this.log("发现 Buttonless 特征，正在请求设备进入 Bootloader (DfuTarg) 升级模式...");
      await buttonless.startNotifications();
      const enterPromise = new Promise(resolve => {
        buttonless.addEventListener("characteristicvaluechanged", () => resolve());
        this.device.addEventListener("gattserverdisconnected", () => resolve(), { once: true });
      });
      await buttonless.writeValue(new Uint8Array([0x01]));
      await enterPromise;
      return { isBootloader: false };
    }

    if (!control || !packet) {
      throw new Error("设备缺少 DFU 控制或数据特征");
    }

    this.controlChar = control;
    this.packetChar = packet;
    await this.controlChar.startNotifications();
    this.controlChar.addEventListener("characteristicvaluechanged", e => this.handleNotification(e));

    // Disable PRN
    await this.sendControl(new Uint8Array([OP_SET_PRN, 0, 0]));
    return { isBootloader: true };
  }

  handleNotification(event) {
    const data = new Uint8Array(event.target.value.buffer);
    if (this.responseResolvers.length > 0) {
      const resolver = this.responseResolvers.shift();
      resolver(data);
    }
  }

  async sendControl(bytes) {
    return new Promise(async (resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("DFU 控制指令响应超时"));
      }, 10000);

      this.responseResolvers.push(data => {
        clearTimeout(timeout);
        this.log(`← 响应: [${Array.from(data).map(b => '0x' + b.toString(16)).join(', ')}]`);
        if (data.length < 3 || data[0] !== OP_RESPONSE) {
          return reject(new Error("收到未知格式的响应: " + Array.from(data).map(b => b.toString(16)).join(" ")));
        }
        const opcode = data[1];
        const result = data[2];
        if (result !== 0x01) {
          let errText = DFU_RESULTS[result] || `错误码 0x${result.toString(16)}`;
          if (result === 0x0b && data.length > 3) {
            const ext = data[3];
            errText += `: ${EXTENDED_ERRORS[ext] || '0x' + ext.toString(16)}`;
          }
          return reject(new Error(`指令 0x${opcode.toString(16)} 失败: ${errText}`));
        }
        resolve(data);
      });

      try {
        this.log(`→ 发送指令: [${Array.from(bytes).map(b => '0x' + b.toString(16)).join(', ')}]`);
        await this.controlChar.writeValue(bytes);
      } catch (e) {
        clearTimeout(timeout);
        reject(e);
      }
    });
  }

  async selectObject(type) {
    const resp = await this.sendControl(new Uint8Array([OP_SELECT, type]));
    const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const maxSize = view.getUint32(3, true);
    const offset = view.getUint32(7, true);
    const crc = view.getUint32(11, true);
    return { maxSize, offset, crc };
  }

  async createObject(type, size) {
    const buffer = new ArrayBuffer(6);
    const view = new DataView(buffer);
    view.setUint8(0, OP_CREATE);
    view.setUint8(1, type);
    view.setUint32(2, size, true);
    return await this.sendControl(new Uint8Array(buffer));
  }

  async getChecksum() {
    const resp = await this.sendControl(new Uint8Array([OP_CRC]));
    const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const offset = view.getUint32(3, true);
    const crc = view.getUint32(7, true);
    return { offset, crc };
  }

  async execute() {
    return await this.sendControl(new Uint8Array([OP_EXECUTE]));
  }

  calculateCrc(bytes, initialCrc = 0xFFFFFFFF) {
    let crc = initialCrc;
    for (let i = 0; i < bytes.length; i++) {
      crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
    }
    return crc >>> 0;
  }

  calculateFwCrc(bytes) {
    return (this.calculateCrc(bytes) ^ 0xFFFFFFFF) >>> 0;
  }

  async sendData(bytes, onChunk) {
    const chunkSize = 20;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
      await this.packetChar.writeValueWithoutResponse(chunk);
      if (onChunk) onChunk(i + chunk.length);
      // 25ms 节奏流控，彻底防止 nRF52 蓝牙 FIFO 溢出
      await new Promise(r => setTimeout(r, 25));
    }
  }

  async transferInit(initBytes) {
    this.log(`准备写入 init packet (${initBytes.length} 字节)...`);
    const select = await this.selectObject(OBJECT_COMMAND);
    this.log(`Init command 槽位信息: maxSize=${select.maxSize}, offset=${select.offset}, crc=0x${select.crc.toString(16)}`);

    const expectedCrc = this.calculateFwCrc(initBytes);
    if (select.offset === initBytes.length && select.crc === expectedCrc) {
      this.log("设备已存在匹配的 init packet，跳过写入直接执行...");
    } else {
      await this.createObject(OBJECT_COMMAND, initBytes.length);
      await this.sendData(initBytes);
      const chk = await this.getChecksum();
      if (chk.offset !== initBytes.length || chk.crc !== expectedCrc) {
        throw new Error(`Init packet CRC 校验不匹配: device=0x${chk.crc.toString(16)}, calc=0x${expectedCrc.toString(16)}`);
      }
    }
    await this.execute();
    this.log("Init packet 写入并执行通过。");
  }

  async transferFirmware(fwBytes) {
    this.log(`准备写入应用固件 (${fwBytes.length} 字节)...`);
    const select = await this.selectObject(OBJECT_DATA);
    const maxSize = select.maxSize;
    let offset = select.offset;
    const deviceCrc = select.crc;

    this.log(`Data 槽位: maxSize=${maxSize}, 设备当前上报 offset=${offset}, crc=0x${deviceCrc.toString(16)}`);

    // 官方 nRF DFU 断点恢复机制：如果上次因丢包中断，需检查已写入部分是否完全正确
    if (offset > 0) {
      const remainder = offset % maxSize;
      const expectedCrcAtOffset = this.calculateFwCrc(fwBytes.subarray(0, offset));
      if (deviceCrc !== expectedCrcAtOffset || remainder !== 0) {
        // 数据受损或未停在完整 page 边界，回退到上一个已完整执行的 Page 边界
        offset = Math.floor(offset / maxSize) * maxSize;
        this.log(`检测到未对齐或校验异常的残留断点，已自动回退到安全页边界: offset=${offset}`);
      } else {
        this.log(`断点已通过校验，可直接增量续传: offset=${offset}`);
      }
    }

    const total = fwBytes.length;
    while (offset < total) {
      const blockSize = Math.min(maxSize, total - offset);
      this.log(`创建数据块: offset=${offset}, block=${blockSize}...`);
      await this.createObject(OBJECT_DATA, blockSize);

      const blockBytes = fwBytes.subarray(offset, offset + blockSize);
      await this.sendData(blockBytes, bytesWritten => {
        const cur = offset + bytesWritten;
        this.progress({
          object: "firmware",
          currentBytes: cur,
          totalBytes: total
        });
      });

      const chk = await this.getChecksum();
      const expectedOffset = offset + blockSize;
      const expectedCrc = this.calculateFwCrc(fwBytes.subarray(0, expectedOffset));
      if (chk.offset !== expectedOffset || chk.crc !== expectedCrc) {
        throw new Error(`数据块校验失败: offset=${chk.offset}/${expectedOffset}, crc=0x${chk.crc.toString(16)}/0x${expectedCrc.toString(16)}`);
      }

      await this.execute();
      offset = expectedOffset;
      this.log(`块写入成功: ${offset}/${total} (${Math.round(offset*100/total)}%)`);
    }
  }
}
