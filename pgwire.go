package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// queryCrtshPostgres runs a read-only SQL query against crt.sh:5432 (user=guest, db=certwatch)
// using the PostgreSQL v3 simple-query wire protocol without requiring external drivers or psql.
func queryCrtshPostgres(ctx context.Context, sqlQuery string, timeout time.Duration) ([][]string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", "crt.sh:5432")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Negotiate SSL if supported by crt.sh PostgreSQL.
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], 80877103)
	if _, err := conn.Write(sslReq[:]); err != nil {
		return nil, err
	}
	var sslResp [1]byte
	if _, err := io.ReadFull(conn, sslResp[:]); err != nil {
		return nil, err
	}
	if sslResp[0] == 'S' {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: "crt.sh"})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	} else if sslResp[0] != 'N' {
		return nil, fmt.Errorf("unexpected Postgres SSL response %q", sslResp[0])
	}

	if err := pgSendStartup(conn, "guest", "certwatch"); err != nil {
		return nil, err
	}
	r := bufio.NewReader(conn)
	if err := pgWaitReady(r); err != nil {
		return nil, err
	}

	if err := pgSendQuery(conn, sqlQuery); err != nil {
		return nil, err
	}

	rows, err := pgReadQueryRows(r)
	_, _ = conn.Write([]byte{'X', 0, 0, 0, 4}) // Terminate
	return rows, err
}

func pgSendStartup(w io.Writer, user, database string) error {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, uint32(196608)) // v3.0
	body.WriteString("user\x00" + user + "\x00")
	body.WriteString("database\x00" + database + "\x00")
	body.WriteByte(0)

	var pkt bytes.Buffer
	_ = binary.Write(&pkt, binary.BigEndian, uint32(4+body.Len()))
	pkt.Write(body.Bytes())
	_, err := w.Write(pkt.Bytes())
	return err
}

func pgSendQuery(w io.Writer, sql string) error {
	var pkt bytes.Buffer
	pkt.WriteByte('Q')
	_ = binary.Write(&pkt, binary.BigEndian, uint32(4+len(sql)+1))
	pkt.WriteString(sql)
	pkt.WriteByte(0)
	_, err := w.Write(pkt.Bytes())
	return err
}

func pgReadMsg(r *bufio.Reader) (byte, []byte, error) {
	msgType, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	msgLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if msgLen < 4 || msgLen > 32<<20 {
		return 0, nil, fmt.Errorf("invalid Postgres message length %d", msgLen)
	}
	payload := make([]byte, msgLen-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

func pgWaitReady(r *bufio.Reader) error {
	for {
		t, payload, err := pgReadMsg(r)
		if err != nil {
			return err
		}
		switch t {
		case 'R':
			if len(payload) < 4 {
				return errors.New("short Postgres auth packet")
			}
			authType := binary.BigEndian.Uint32(payload[0:4])
			if authType != 0 {
				return fmt.Errorf("unsupported Postgres auth type %d", authType)
			}
		case 'E':
			return errors.New(pgParseError(payload))
		case 'Z':
			return nil
		case 'S', 'K', 'N':
			// Ignore parameter status, backend key, notices.
		}
	}
}

func pgReadQueryRows(r *bufio.Reader) ([][]string, error) {
	var rows [][]string
	var queryErr error
	for {
		t, payload, err := pgReadMsg(r)
		if err != nil {
			return rows, err
		}
		switch t {
		case 'D':
			row, err := pgParseDataRow(payload)
			if err == nil {
				rows = append(rows, row)
			}
		case 'E':
			queryErr = errors.New(pgParseError(payload))
		case 'Z':
			return rows, queryErr
		}
	}
}

func pgParseDataRow(payload []byte) ([]string, error) {
	if len(payload) < 2 {
		return nil, errors.New("short DataRow")
	}
	cols := int(binary.BigEndian.Uint16(payload[0:2]))
	off := 2
	row := make([]string, cols)
	for i := 0; i < cols; i++ {
		if off+4 > len(payload) {
			return nil, errors.New("truncated DataRow column length")
		}
		colLen := int(int32(binary.BigEndian.Uint32(payload[off : off+4])))
		off += 4
		if colLen < 0 {
			row[i] = ""
			continue
		}
		if off+colLen > len(payload) {
			return nil, errors.New("truncated DataRow value")
		}
		row[i] = string(payload[off : off+colLen])
		off += colLen
	}
	return row, nil
}

func pgParseError(payload []byte) string {
	var msg, code string
	for off := 0; off < len(payload); {
		field := payload[off]
		off++
		if field == 0 {
			break
		}
		end := bytes.IndexByte(payload[off:], 0)
		if end < 0 {
			break
		}
		val := string(payload[off : off+end])
		off += end + 1
		switch field {
		case 'M':
			msg = val
		case 'C':
			code = val
		}
	}
	if msg == "" {
		return "postgres error"
	}
	if code != "" {
		return fmt.Sprintf("postgres (%s): %s", code, msg)
	}
	return "postgres: " + msg
}

func sanitizeTSQueryDomain(domain string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(domain) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), ".")
}
