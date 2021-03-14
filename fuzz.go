package pe

func Fuzz(data []byte) int {
	f, err := NewBytes(data, &Options{Fast: false, SectionEntropy: true})
	if err != nil {
		return 0
	}
	err = f.Parse()
	if err != nil {
		return 0
	}
	return 1
}
