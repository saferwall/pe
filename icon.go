package pe

import (
	"bytes"
	"errors"
	"image/png"
)

func (pe *File) ParsePngIcon() ([]byte, error) {
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

		_, err = png.Decode(bytes.NewBuffer(b))
		if err != nil {
			continue
		}
		return b, nil
	}
	return nil, errors.New("no valid png icon found")
}
