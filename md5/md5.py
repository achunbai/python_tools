import hashlib
import sys

def crc16_cal(buf, crc=0xFFFF):
    for byte in buf:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF  # 保持CRC为16位
    return crc

def verify_firmware_md5(firmware_path):
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    # MD5验证
    possible_md5_lengths = [16, 8]
    valid_md5 = False

    for md5_length in possible_md5_lengths:
        if len(data) < md5_length:
            print(f"固件文件大小小于指定的MD5长度({md5_length}字节)。")
            continue
        stored_md5 = data[-md5_length:].hex()
        firmware_data = data[:-md5_length]
        calculated_md5_full = hashlib.md5(firmware_data).hexdigest()
        calculated_md5 = calculated_md5_full[:md5_length * 2]
        
        print(f"使用{md5_length}字节的存储MD5: {stored_md5}")
        print(f"使用{md5_length}字节的计算MD5: {calculated_md5}")
        
        if stored_md5 == calculated_md5:
            print(f"MD5验证通过（使用{md5_length}字节）。\n")
            valid_md5 = True
            break
        else:
            print(f"使用{md5_length}字节的MD5验证失败。\n")
    
    if not valid_md5:
        print("所有MD5验证均失败。\n")
    
    # CRC16验证
    if len(data) < 2:
        print("固件文件大小小于CRC16长度（2字节）。")
    else:
        stored_crc16 = int.from_bytes(data[-2:], byteorder='big')
        firmware_data_crc = data[:-2]
        calculated_crc16 = crc16_cal(firmware_data_crc)
        
        print(f"存储的CRC16: {stored_crc16:04X}")
        print(f"计算的CRC16: {calculated_crc16:04X}")
        
        if stored_crc16 == calculated_crc16:
            print("CRC16验证通过。\n")
        else:
            print("CRC16验证失败。\n")
    
    # 计算整个文件的MD5
    full_file_md5 = hashlib.md5(data).hexdigest()
    print(f"整个文件的MD5: {full_file_md5}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python verify_md5.py <固件文件路径>")
    else:
        firmware_path = sys.argv[1]
        verify_firmware_md5(firmware_path)