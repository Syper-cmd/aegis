package compress

import (
	"bytes"
	"compress/zlib"
	"io"
)

// CompressZlib стискає масив байтів за допомогою алгоритму zlib (DEFLATE)
func CompressZlib(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		return nil, err
	}

	// Обов'язково закриваємо writer, щоб він скинув залишкові байти (flush) у буфер
	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecompressZlib розпаковує масив байтів, стиснутий zlib
func DecompressZlib(data []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}
