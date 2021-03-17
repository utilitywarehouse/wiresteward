package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// https://stackoverflow.com/questions/48050945/how-to-unmarshal-json-into-durations/54571600#54571600
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		d.Duration = tmp
		return nil
	default:
		return fmt.Errorf("Invalid duration of type %v", value)
	}
}
