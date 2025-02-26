package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"

	"github.com/gabriel-vasile/mimetype"
)

// ParseIconToPng 解析icon，并转换为png
func (pe *File) ParseIconToPng() ([]byte, error) {
	iconDataList, err := pe.ParseIcon()
	if err != nil {
		return nil, err
	}
	var maxIconData []byte
	for _, data := range iconDataList {
		if mimetype.Detect(data).Is("image/png") {
			return data, nil
		}
		if len(data) > len(maxIconData) {
			maxIconData = data
		}
	}

	// BIP file
	if bytes.HasPrefix(maxIconData, []byte{0x28, 0x00, 0x00, 0x00}) {
		return BIPToPNG(maxIconData)
	}

	img, _, err := image.Decode(bytes.NewReader(maxIconData))
	if err != nil {
		return nil, err
	}
	result := bytes.NewBuffer(nil)
	err = png.Encode(result, img)
	if err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func (pe *File) ParseIcon() ([][]byte, error) {
	var iconEntry *ResourceDirectoryEntry
	for _, e := range pe.Resources.Entries {
		if e.ID != RTIcon {
			continue
		}
		if len(e.Directory.Entries) == 0 {
			return nil, errors.New("no entries found in resource directory")
		}
		iconEntry = &e
		break
	}
	if iconEntry == nil {
		return nil, errors.New("no icon found in resource directory")
	}

	iconDataList := make([][]byte, 0)

	for _, iconItem := range iconEntry.Directory.Entries {
		if len(iconItem.Directory.Entries) == 0 {
			continue
		}

		iconData := &iconItem.Directory.Entries[0]

		offset, size := pe.GetOffsetFromRva(iconData.Data.Struct.OffsetToData), iconData.Data.Struct.Size

		b, err := pe.ReadBytesAtOffset(offset, size)
		if err != nil {
			return nil, err
		}

		iconDataList = append(iconDataList, b)
	}
	return iconDataList, nil
}

// BIP文件头结构
const (
	headerSize      = 40
	magicNumberSize = 4
)

// BIPToPNG BIP转PNG处理函数
func BIPToPNG(bipData []byte) ([]byte, error) {
	// 检查BIP文件头（示例中的magic number）
	if !bytes.HasPrefix(bipData, []byte{0x28, 0x00, 0x00, 0x00}) {
		return nil, fmt.Errorf("invalid bip file") // 或返回错误
	}

	// 解析宽高（小端序）
	width := binary.LittleEndian.Uint32(bipData[magicNumberSize : magicNumberSize+4])
	height := binary.LittleEndian.Uint32(bipData[magicNumberSize+4 : headerSize])

	bipData = convertToRGBA(bipData, int(width), int(height))

	// 创建RGBA图像
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	copy(img.Pix, bipData[headerSize:]) // 跳过文件头

	// 计算裁剪区域（优先保留下半部分）
	cropped := img.SubImage(image.Rect(
		0,
		int(width),
		int(width),
		0,
	)).(*image.RGBA)

	flipImageVertically(cropped)

	buf := bytes.NewBuffer(nil)

	err := png.Encode(buf, cropped)
	if err != nil {
		return nil, fmt.Errorf("fail to encode PNG image: %w", err)
	}
	return buf.Bytes(), nil
}

// 垂直翻转图像函数
func flipImageVertically(img *image.RGBA) {
	height := img.Rect.Dy()
	stride := img.Stride
	pix := img.Pix

	// 创建行缓冲区
	lineBuffer := make([]byte, stride)

	// 遍历上半部分图像
	for y := 0; y < height/2; y++ {
		// 计算上下行位置
		top := y * stride
		bottom := (height - 1 - y) * stride

		// 交换两行像素
		copy(lineBuffer, pix[top:top+stride])                // 暂存上行
		copy(pix[top:top+stride], pix[bottom:bottom+stride]) // 下行复制到上行
		copy(pix[bottom:bottom+stride], lineBuffer)          // 缓冲区复制到下行
	}
}

func convertToRGBA(data []byte, width, height int) []byte {
	output := make([]byte, len(data))
	for i := 0; i < len(data); i += 4 {
		// BGR → RGB 转换
		output[i] = data[i+2]   // R
		output[i+1] = data[i+1] // G
		output[i+2] = data[i]   // B
		output[i+3] = data[i+3] // A
	}
	return output
}
