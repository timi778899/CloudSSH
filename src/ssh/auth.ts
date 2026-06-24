import { SSH_MSG_USERAUTH_REQUEST, SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, AuthResult } from '../types';
import { encodeString, concat, readUint32, toSSHMPInt } from './utils';

type SignAlgorithm = string | { name: string };

type PublicKeyAuthMaterial = {
  algorithm: string;
  signingKey: CryptoKey;
  publicKeyBlob: Uint8Array;
  signAlgorithm: SignAlgorithm;
};

export class SSHAuth {
  static buildPasswordAuthRequest(
    username: string,
    password: string
  ): Uint8Array {
    const parts: Uint8Array[] = [
      new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
      encodeString(username),
      encodeString('ssh-connection'),
      encodeString('password'),
      new Uint8Array([0x00]),
      encodeString(password),
    ];

    return concat(...parts);
  }

  /**
   * Build a public key auth request.
   * The signature covers: session_id_string || SSH_MSG_USERAUTH_REQUEST || user || service || "publickey" || TRUE || key algorithm || pubkey_blob
   */
  static async buildPublicKeyAuthRequest(
    username: string,
    privateKeyPEM: string,
    sessionID: Uint8Array
  ): Promise<Uint8Array> {
    const { algorithm, signingKey, publicKeyBlob, signAlgorithm } = await this.parsePrivateKey(privateKeyPEM);

    const requestBody = concat(
      new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
      encodeString(username),
      encodeString('ssh-connection'),
      encodeString('publickey'),
      new Uint8Array([0x01]),
      encodeString(algorithm),
      encodeString(publicKeyBlob),
    );

    const dataToSign = concat(encodeString(sessionID), requestBody);
    const rawSignature = new Uint8Array(await crypto.subtle.sign(signAlgorithm as any, signingKey, dataToSign));

    const signatureBlob = concat(
      encodeString(algorithm),
      encodeString(rawSignature),
    );

    return concat(requestBody, encodeString(signatureBlob));
  }

  private static async parsePrivateKey(pem: string): Promise<PublicKeyAuthMaterial> {
    if (pem.includes('-----BEGIN RSA PRIVATE KEY-----')) {
      return this.parseRSAPrivateKey(pem);
    }

    if (pem.includes('-----BEGIN PRIVATE KEY-----')) {
      return this.parsePKCS8RSAPrivateKey(pem);
    }

    if (pem.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
      throw new Error('不支持加密的 RSA 私钥，请先移除私钥密码');
    }

    if (pem.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) {
      return this.parseOpenSSHPrivateKey(pem);
    }

    throw new Error('不支持的私钥格式，请使用 OpenSSH Ed25519 或 RSA PRIVATE KEY 私钥');
  }

  /**
   * Parse an OpenSSH Ed25519 private key.
   * Encrypted keys are not supported.
   */
  private static async parseOpenSSHPrivateKey(pem: string): Promise<PublicKeyAuthMaterial> {
    const raw = this.pemToBytes(pem);

    const magic = 'openssh-key-v1\0';
    const magicBytes = new TextEncoder().encode(magic);
    for (let i = 0; i < magicBytes.length; i++) {
      if (raw[i] !== magicBytes[i]) {
        throw new Error('不支持的 OpenSSH 私钥格式');
      }
    }
    let offset = magicBytes.length;

    const cipherLen = readUint32(raw, offset); offset += 4;
    const cipher = new TextDecoder().decode(raw.slice(offset, offset + cipherLen)); offset += cipherLen;
    if (cipher !== 'none') throw new Error('不支持加密的私钥，请使用 ssh-keygen -p 移除密码');

    const kdfLen = readUint32(raw, offset); offset += 4 + kdfLen;
    const kdfOptLen = readUint32(raw, offset); offset += 4 + kdfOptLen;
    const numKeys = readUint32(raw, offset); offset += 4;
    if (numKeys !== 1) throw new Error('仅支持单密钥文件');

    const pubSecLen = readUint32(raw, offset); offset += 4 + pubSecLen;

    const privSecLen = readUint32(raw, offset); offset += 4;
    const privSection = raw.slice(offset, offset + privSecLen);

    let po = 8; // checkint1 + checkint2

    const ktLen = readUint32(privSection, po); po += 4;
    const keyType = new TextDecoder().decode(privSection.slice(po, po + ktLen)); po += ktLen;
    if (keyType === 'ssh-ed25519') {
      const pubKeyLen = readUint32(privSection, po); po += 4;
      const pubKeyRaw = privSection.slice(po, po + pubKeyLen); po += pubKeyLen;

      const privKeyLen = readUint32(privSection, po); po += 4;
      const privKeyRaw = privSection.slice(po, po + privKeyLen);
      const seed = privKeyRaw.slice(0, 32);

      const signingKey = await crypto.subtle.importKey(
        'pkcs8',
        this.buildEd25519PKCS8(seed),
        { name: 'Ed25519' },
        false,
        ['sign']
      );

      const publicKeyBlob = concat(
        encodeString('ssh-ed25519'),
        encodeString(pubKeyRaw),
      );

      return {
        algorithm: 'ssh-ed25519',
        signingKey,
        publicKeyBlob,
        signAlgorithm: 'Ed25519',
      };
    }

    if (keyType === 'ssh-rsa') {
      const n = this.readSSHString(privSection, po); po = n.nextOffset;
      const e = this.readSSHString(privSection, po); po = e.nextOffset;
      const d = this.readSSHString(privSection, po); po = d.nextOffset;
      const qi = this.readSSHString(privSection, po); po = qi.nextOffset;
      const p = this.readSSHString(privSection, po); po = p.nextOffset;
      const q = this.readSSHString(privSection, po);

      return this.buildRSAMaterial(n.value, e.value, d.value, p.value, q.value, qi.value);
    }

    throw new Error(`不支持的 OpenSSH 密钥类型: ${keyType}，请使用 ssh-ed25519 或 RSA 私钥`);
  }

  /**
   * Parse an unencrypted PKCS#1 RSA private key:
   * SEQUENCE(version, n, e, d, p, q, dp, dq, qi)
   */
  private static async parseRSAPrivateKey(pem: string): Promise<PublicKeyAuthMaterial> {
    return this.parsePKCS1RSAPrivateKey(this.pemToBytes(pem));
  }

  private static async parsePKCS8RSAPrivateKey(pem: string): Promise<PublicKeyAuthMaterial> {
    const der = this.pemToBytes(pem);
    const sequence = this.readDerElement(der, 0, 0x30);
    let offset = sequence.contentStart;

    const version = this.readDerElement(der, offset, 0x02);
    offset = version.nextOffset;

    const algorithm = this.readDerElement(der, offset, 0x30);
    offset = algorithm.nextOffset;

    const privateKey = this.readDerElement(der, offset, 0x04);
    const pkcs1 = der.slice(privateKey.contentStart, privateKey.contentEnd);

    return this.parsePKCS1RSAPrivateKey(pkcs1);
  }

  private static async parsePKCS1RSAPrivateKey(der: Uint8Array): Promise<PublicKeyAuthMaterial> {
    const sequence = this.readDerElement(der, 0, 0x30);
    let offset = sequence.contentStart;
    const end = sequence.contentEnd;

    const integers: Uint8Array[] = [];
    while (offset < end) {
      const element = this.readDerElement(der, offset, 0x02);
      integers.push(der.slice(element.contentStart, element.contentEnd));
      offset = element.nextOffset;
    }

    if (integers.length < 9) {
      throw new Error('RSA 私钥格式无效，请确认是未加密的 PKCS#1 RSA PRIVATE KEY');
    }

    const [, n, e, d, p, q, , , qi] = integers.map((value) => this.stripLeadingZeroes(value));

    return this.buildRSAMaterial(n, e, d, p, q, qi);
  }

  private static async buildRSAMaterial(
    nRaw: Uint8Array,
    eRaw: Uint8Array,
    dRaw: Uint8Array,
    pRaw: Uint8Array,
    qRaw: Uint8Array,
    qiRaw: Uint8Array
  ): Promise<PublicKeyAuthMaterial> {
    const n = this.stripLeadingZeroes(nRaw);
    const e = this.stripLeadingZeroes(eRaw);
    const d = this.stripLeadingZeroes(dRaw);
    const p = this.stripLeadingZeroes(pRaw);
    const q = this.stripLeadingZeroes(qRaw);
    const qi = this.stripLeadingZeroes(qiRaw);
    const dBig = this.bytesToBigInt(d);
    const pBig = this.bytesToBigInt(p);
    const qBig = this.bytesToBigInt(q);
    const dp = this.bigIntToBytes(dBig % (pBig - 1n));
    const dq = this.bigIntToBytes(dBig % (qBig - 1n));

    const jwk: JsonWebKey = {
      kty: 'RSA',
      n: this.base64UrlEncode(n),
      e: this.base64UrlEncode(e),
      d: this.base64UrlEncode(d),
      p: this.base64UrlEncode(p),
      q: this.base64UrlEncode(q),
      dp: this.base64UrlEncode(dp),
      dq: this.base64UrlEncode(dq),
      qi: this.base64UrlEncode(qi),
      ext: false,
      key_ops: ['sign'],
    };

    const signingKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const publicKeyBlob = concat(
      encodeString('ssh-rsa'),
      toSSHMPInt(e),
      toSSHMPInt(n),
    );

    return {
      algorithm: 'rsa-sha2-256',
      signingKey,
      publicKeyBlob,
      signAlgorithm: { name: 'RSASSA-PKCS1-v1_5' },
    };
  }

  /**
   * Wrap a 32-byte Ed25519 seed into PKCS8 DER format for Web Crypto import.
   */
  private static buildEd25519PKCS8(seed: Uint8Array): Uint8Array {
    const oid = new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70]);
    const seedOctet = new Uint8Array([0x04, seed.length, ...seed]);
    const innerOctet = new Uint8Array([0x04, seedOctet.length, ...seedOctet]);
    const algoSeq = new Uint8Array([0x30, oid.length, ...oid]);
    const version = new Uint8Array([0x02, 0x01, 0x00]);
    const totalLen = version.length + algoSeq.length + innerOctet.length;
    return new Uint8Array([0x30, totalLen, ...version, ...algoSeq, ...innerOctet]);
  }

  private static pemToBytes(pem: string): Uint8Array {
    const b64 = pem.trim().split(/\r?\n/).filter(line => !line.startsWith('-----')).join('');
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  private static readDerElement(data: Uint8Array, offset: number, expectedTag: number): {
    contentStart: number;
    contentEnd: number;
    nextOffset: number;
  } {
    if (data[offset] !== expectedTag) {
      throw new Error('RSA 私钥 DER 结构无效');
    }

    const lengthInfo = this.readDerLength(data, offset + 1);
    const contentStart = lengthInfo.nextOffset;
    const contentEnd = contentStart + lengthInfo.length;
    if (contentEnd > data.length) {
      throw new Error('RSA 私钥 DER 长度无效');
    }

    return { contentStart, contentEnd, nextOffset: contentEnd };
  }

  private static readDerLength(data: Uint8Array, offset: number): { length: number; nextOffset: number } {
    const first = data[offset];
    if ((first & 0x80) === 0) {
      return { length: first, nextOffset: offset + 1 };
    }

    const byteCount = first & 0x7f;
    if (byteCount === 0 || byteCount > 4) {
      throw new Error('RSA 私钥 DER 长度格式无效');
    }

    let length = 0;
    for (let i = 0; i < byteCount; i++) {
      length = (length << 8) | data[offset + 1 + i];
    }

    return { length, nextOffset: offset + 1 + byteCount };
  }

  private static stripLeadingZeroes(bytes: Uint8Array): Uint8Array {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    return bytes.slice(start);
  }

  private static readSSHString(data: Uint8Array, offset: number): { value: Uint8Array; nextOffset: number } {
    const length = readUint32(data, offset);
    const contentStart = offset + 4;
    const contentEnd = contentStart + length;
    if (contentEnd > data.length) {
      throw new Error('OpenSSH 私钥结构无效');
    }

    return {
      value: data.slice(contentStart, contentEnd),
      nextOffset: contentEnd,
    };
  }

  private static bytesToBigInt(bytes: Uint8Array): bigint {
    let value = 0n;
    for (const byte of bytes) {
      value = (value << 8n) | BigInt(byte);
    }
    return value;
  }

  private static bigIntToBytes(value: bigint): Uint8Array {
    if (value === 0n) return new Uint8Array([0]);
    const bytes: number[] = [];
    let current = value;
    while (current > 0n) {
      bytes.unshift(Number(current & 0xffn));
      current >>= 8n;
    }
    return new Uint8Array(bytes);
  }

  private static base64UrlEncode(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  static handleResponse(payload: Uint8Array): AuthResult {
    const msgType = payload[0];

    switch (msgType) {
      case SSH_MSG_USERAUTH_SUCCESS:
        return { success: true };

      case SSH_MSG_USERAUTH_FAILURE: {
        const len = readUint32(payload, 1);
        const methods = new TextDecoder().decode(
          payload.slice(5, 5 + len)
        );
        return {
          success: false,
          allowedMethods: methods.split(','),
        };
      }

      default:
        throw new Error(`Unexpected auth message type: ${msgType}`);
    }
  }
}
