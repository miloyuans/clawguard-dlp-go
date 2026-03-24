package audit
import("encoding/json";"os";"time")
type Record struct{Time time.Time `json:"time"`; UserID string `json:"userId"`; Action string `json:"action"`; Findings interface{} `json:"findings"`}
type Logger struct{path string}
func New(path string)*Logger{return &Logger{path:path}}
func (l *Logger) Write(r Record) error {f,err:=os.OpenFile(l.path,os.O_APPEND|os.O_CREATE|os.O_WRONLY,0o600); if err!=nil{return err}; defer f.Close(); return json.NewEncoder(f).Encode(r)}
