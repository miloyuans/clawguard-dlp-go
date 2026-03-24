package policy

type Action string
const (AllowRedacted Action="ALLOW_REDACTED"; Block Action="BLOCK"; LocalOnly Action="LOCAL_ONLY")
type Input struct{UserID string; HitHigh bool}
type Engine struct{Default Action; High Action}
func NewEngine(defaultAct,highAct Action)*Engine{return &Engine{Default:defaultAct,High:highAct}}
func (e *Engine) Decide(in Input) Action { if in.HitHigh {return e.High}; return e.Default }
