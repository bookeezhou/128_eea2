package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"io"
	"math"
	"math/big"
	"os"
	"strconv"
)

// 根据T规则
// T = COUNT||BEARER||DIRECTION||026||T0
// T[15-0]byte
func make_T(count []byte, bearer byte, direction byte, t0 uint32) []byte {
	T := make([]byte, 16)

	T[0] = count[0]
	T[1] = count[1]
	T[2] = count[2]
	T[3] = count[3]
	T[4] = ((bearer << 1) | (direction & 0xF1)) << 2
	// 26 bits,T[4:2bits---8] 为零,golang初始变量已经清零

	// 64 bits t0 ,T[0-7]赋值为t0
	t0_slice := make([]byte, 4)
	binary.BigEndian.PutUint32(t0_slice, t0)
	glog.Errorf("% 0X---%d", t0_slice, t0)
	copy(T[12:], t0_slice)
	glog.Errorf("T%d---% 0X", t0, T)
	return T
}

// 使用EEA2算法ID生成S
// KNASenc生成256bits,截断生成128bits
func make_KNASenc_EEA2(kasme []byte) []byte {
	s_message := make([]byte, 7)
	s_message[0] = 0x15 // FC 密钥推倒标识
	s_message[1] = 0x01 // P0
	s_message[2] = 0x01 // L0
	s_message[3] = 0x00
	s_message[4] = 0x02 // P1
	s_message[5] = 0x01 // L1
	s_message[6] = 0x00
	h := hmac.New(sha256.New, kasme)
	h.Write(s_message)

	// 256bits KNASenc截断高128bits,留低128bits
	return (h.Sum(nil))[:128]
}

// 生成密钥块
func aes_ctr_128(T []byte, key []byte) cipher.Stream {
	block, _ := aes.NewCipher(key)

	stream := cipher.NewCTR(block, T)
	return stream
}

func make_NAS_count(nas_overflow uint16, nas_sqn byte) []byte {
	nas_count := make([]byte, 4)
	nas_count[0] = nas_sqn
	nas_overflow_bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(nas_overflow_bytes, nas_overflow)
	copy(nas_count[1:], nas_overflow_bytes)
	return nas_count
}

func eea2_decrypt(nas_overflow uint16, nas_sqn byte, bearer byte, direction byte, kasme []byte,
	cipher_txt []byte, cipher_bit_length uint32) []byte {
	var bit_128_count_block uint32 = cipher_bit_length / 128
	var bit_128_remaining_block uint32 = cipher_bit_length % 128
	var bit_remaining_of_byte uint32 = bit_128_remaining_block % 8
	glog.Errorf("bit_of_byte:%d", bit_remaining_of_byte)

	nas_count := make_NAS_count(nas_overflow, nas_sqn)
	KNASenc_eea2 := make_KNASenc_EEA2(kasme)

	plain_txt := make([]byte, len(cipher_txt))

	//loop for 128bits
	var t0_increase uint32
	to_incr_big := big.NewInt(0)
	one_big := big.NewInt(1)
	exp_2_64_big := big.NewInt(0)
	exp_2_64_big.Exp(big.NewInt(2), big.NewInt(64), nil)
	mod_data := big.NewInt(0)

	glog.Errorf("count_block:%d", bit_128_count_block)

	for t0_increase < bit_128_count_block {
		T := make_T(nas_count, bearer, direction, t0_increase)
		stream := aes_ctr_128(T, KNASenc_eea2)
		stream.XORKeyStream(plain_txt[t0_increase*16:], cipher_txt[t0_increase*16:(t0_increase+1)*16])

		mod_data.Mod(to_incr_big.Add(to_incr_big, one_big), exp_2_64_big)
		t0_increase = uint32(mod_data.Uint64())
	}

	if bit_128_remaining_block != 0 {
		// less than 128bits
		T_last := make_T(nas_count, bearer, direction, t0_increase)
		stream_last := aes_ctr_128(T_last, KNASenc_eea2)
		stream_last.XORKeyStream(plain_txt[t0_increase*16:], cipher_txt[t0_increase*16:])
	}

	glog.Errorf("plain_text:% 0X", plain_txt)

	// 截断多余的bit位
	remaining_bytes := bit_128_remaining_block / 8
	glog.Errorf("bit_128_remain:%d---byte:%d", bit_128_remaining_block, remaining_bytes)
	last_byte_index := t0_increase*16 + remaining_bytes
	plain_txt[last_byte_index] = (plain_txt[last_byte_index] >> (8 - bit_remaining_of_byte)) << (8 - bit_remaining_of_byte)

	glog.Errorf("% 0X", plain_txt)

	return plain_txt
}

func eea2_decrypt_simple(count []byte, key []byte, bearer byte, direction byte,
	cipher_txt []byte, cipher_bit_length uint32) []byte {
	var bit_128_count_block uint32 = cipher_bit_length / 128
	var bit_128_remaining_block uint32 = cipher_bit_length % 128
	var bit_remaining_of_byte uint32 = bit_128_remaining_block % 8
	glog.Errorf("bit_of_byte:%d", bit_remaining_of_byte)

	plain_txt := make([]byte, len(cipher_txt))

	nas_count := make([]byte, 4)
	copy(nas_count, count)
	KNASenc_eea2 := make([]byte, 16)
	copy(KNASenc_eea2, key)

	//loop for 128bits
	var t0_increase uint32
	to_incr_big := big.NewInt(0)
	one_big := big.NewInt(1)
	exp_2_64_big := big.NewInt(0)
	exp_2_64_big.Exp(big.NewInt(2), big.NewInt(64), nil)
	mod_data := big.NewInt(0)

	glog.Errorf("count_block:%d", bit_128_count_block)

	for t0_increase < bit_128_count_block {
		T := make_T(nas_count, bearer, direction, t0_increase)
		stream := aes_ctr_128(T, KNASenc_eea2)
		stream.XORKeyStream(plain_txt[t0_increase*16:], cipher_txt[t0_increase*16:(t0_increase+1)*16])

		mod_data.Mod(to_incr_big.Add(to_incr_big, one_big), exp_2_64_big)
		t0_increase = uint32(mod_data.Uint64())
	}

	if bit_128_remaining_block != 0 {
		// less than 128bits
		T_last := make_T(nas_count, bearer, direction, t0_increase)
		stream_last := aes_ctr_128(T_last, KNASenc_eea2)
		stream_last.XORKeyStream(plain_txt[t0_increase*16:], cipher_txt[t0_increase*16:])
	}

	glog.Errorf("plain_text:% 0X", plain_txt)

	// 截断多余的bit位
	remaining_bytes := bit_128_remaining_block / 8
	glog.Errorf("bit_128_remain:%d---byte:%d", bit_128_remaining_block, remaining_bytes)
	last_byte_index := t0_increase*16 + remaining_bytes
	plain_txt[last_byte_index] = (plain_txt[last_byte_index] >> (8 - bit_remaining_of_byte)) << (8 - bit_remaining_of_byte)

	glog.Errorf("% 0X", plain_txt)

	return plain_txt
}

// for input command line
var infile *string = flag.String("i", "infile", "File contains some eea2 paramerters")

func main() {
	flag.Parse()
	if infile == nil {
		fmt.Println("infile = ", *infile, "must be to enter")
		return
	}

	file, err := os.Open(*infile)
	if err != nil {
		fmt.Println("Failed to open the input file", *infile)
		return
	}

	defer file.Close()

	key := make([]byte, 16)
	count := make([]byte, 4)
	var cipher_txt *[]byte
	var bearer byte
	var direction byte
	var length uint32
	//var ciphter_bytes uint32

	br := bufio.NewReader(file)
	for i := 0; ; i++ {
		values, err := br.ReadBytes(';')
		if err != nil && err != io.EOF {
			panic(err)
		}

		if err == io.EOF {
			break
		}

		if i == 0 {
			// for key
			glog.Errorf("key:%v---%d", values, len(values))
			temp := values[:len(values)-1]
			_, err := hex.Decode(key, temp)
			if err != nil {
				glog.Error(err)
			}
			glog.Errorf("%v---%d", key, len(key))
		} else if i == 1 {
			// for count
			glog.Errorf("count:%v---%d", values, len(values))
			temp := values[:len(values)-1]
			_, err := hex.Decode(count, temp)
			if err != nil {
				glog.Error(err)
			}
			glog.Errorf("%v---%d", count, len(count))
		} else if i == 2 {
			// for bearer
			glog.Errorf("bearer:%v---%d", values, len(values))
			temp := values[:len(values)-1]
			bearer_value, err := strconv.Atoi(string(temp))
			if err != nil {
				glog.Error(err)
			}
			bearer = byte(bearer_value)
			glog.Errorf("%d", bearer)
		} else if i == 3 {
			// for direction
			glog.Errorf("direction:%v---%d", values, len(values))
			temp := values[:len(values)-1]
			direc, err := strconv.Atoi(string(temp))
			direction = byte(direc)
			if err != nil {
				glog.Error(err)
			}
			glog.Errorf("%d", direction)
		} else if i == 4 {
			// for length
			glog.Errorf("length:%v---%d", values, len(values))
			temp := values[:len(values)-1]
			bit_len, err := strconv.Atoi(string(temp))
			length = uint32(bit_len)
			if err != nil {
				glog.Error(err)
			}
			glog.Errorf("%d", length)
		} else if i == 5 {
			// for cipher_txt
			glog.Errorf("cipher_txt:%v---%d", values, len(values))
			temp := values[:len(values)-1]
			cipher_temp := make([]byte, len(temp)/2)
			_, err := hex.Decode(cipher_temp, temp)
			if err != nil {
				glog.Error(err)
			}
			cipher_txt = &cipher_temp
			glog.Errorf("% 0X---%d", *cipher_txt, len(*cipher_txt))
			//ciphter_bytes = uint32(len(cipher_txt))
		}
	} // end for

	// for eea2 decryption
	ret := eea2_decrypt_simple(count, key, bearer, direction, *cipher_txt, length)
	if len(ret) != len(*cipher_txt) {
		fmt.Println("EEA2 decryption error")
	} else {
		fmt.Println("EEA2 decryption success")
	}

	glog.Flush()
}
