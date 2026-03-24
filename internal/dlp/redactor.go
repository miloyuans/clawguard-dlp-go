package dlp

import (
    "crypto/sha256"
    "encoding/hex"
    "regexp"
    "strings"
)

type Finding struct { Type string `json:"type"`; ValueHash string `json:"valueHash"`; Count int `json:"count"`; Severity string `json:"severity"` }
type Result struct { RedactedText string `json:"redactedText"`; Findings []Finding `json:"findings"`; HitHigh bool `json:"hitHigh"` }
type Redactor struct{}
var (
    reIPv4=regexp.MustCompile(`\b((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.|$)){4}\b`)
    reEmail=regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
    reBearer=regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`)
    reJWT=regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b`)
    reAWSAK=regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
    rePasswordKV=regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*[^\s\"']+`)
    rePrivKey=regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)
    reKubeCfg=regexp.MustCompile(`(?is)apiVersion:\s*v1\s*kind:\s*Config\s*clusters:`)
)
func NewRedactor()*Redactor{return &Redactor{}}
func hashValue(v string)string{h:=sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:8])}
func (r *Redactor) Run(text string) Result {
    out:=text; findings:=map[string]*Finding{}
    replace:=func(name,severity string,re *regexp.Regexp,placeholder string){
        m:=re.FindAllString(out,-1); if len(m)==0{return}
        for _,v:= range m {k:=name+":"+hashValue(v); if findings[k]==nil{findings[k]=&Finding{Type:name,ValueHash:hashValue(v),Severity:severity}}; findings[k].Count++}
        out=re.ReplaceAllString(out,placeholder)
    }
    replace("IP","medium",reIPv4,"<IP_REDACTED>")
    replace("EMAIL","medium",reEmail,"<EMAIL_REDACTED>")
    replace("BEARER","high",reBearer,"<TOKEN_REDACTED>")
    replace("JWT","high",reJWT,"<JWT_REDACTED>")
    replace("AWS_AK","high",reAWSAK,"<AWS_AK_REDACTED>")
    replace("PASSWORD","high",rePasswordKV,"password=<PASSWORD_REDACTED>")
    if rePrivKey.MatchString(out){out=rePrivKey.ReplaceAllString(out,"<PRIVATE_KEY_REDACTED>"); findings["PRIVATE_KEY:static"]=&Finding{Type:"PRIVATE_KEY",ValueHash:"static",Count:1,Severity:"high"}}
    if reKubeCfg.MatchString(out){out=strings.ReplaceAll(out,"clusters:","clusters: # <KUBECONFIG_REDACTED>"); findings["KUBECONFIG:static"]=&Finding{Type:"KUBECONFIG",ValueHash:"static",Count:1,Severity:"high"}}
    list:=make([]Finding,0,len(findings)); hitHigh:=false
    for _,f:= range findings {list=append(list,*f); if f.Severity=="high"{hitHigh=true}}
    return Result{RedactedText:out,Findings:list,HitHigh:hitHigh}
}
