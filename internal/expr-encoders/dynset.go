package encoders

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Dynset{}, func(e expr.Any) encoder {
		return &dynsetEncoder{dynset: e.(*expr.Dynset)}
	})
}

type dynsetEncoder struct {
	dynset *expr.Dynset
}

func (b *dynsetEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	dyn := b.dynset
	if ctx.rule == nil {
		return nil, errors.New("ctx has no rule")
	}

	srcRegKey, ok := ctx.reg.Get(regID(dyn.SrcRegKey))
	if !ok {
		return nil, errors.Errorf("%T statement has no key expression", dyn)
	}
	exp := srcRegKey.HumanExpr

	tmpRule := nftables.Rule{
		Table: ctx.rule.Table,
		Exprs: dyn.Exprs,
	}
	exprsStr, err := NewRuleExprEncoder(&tmpRule).Format()
	if err != nil {
		return nil, err
	}

	if dyn.Timeout != 0 {
		exp = fmt.Sprintf("%s timeout %s", exp, dyn.Timeout)
	}

	setName := fmt.Sprintf("@%s", dyn.SetName)
	sb := strings.Builder{}

	sb.WriteString(fmt.Sprintf("%s %s { %s", DynSetOP(dyn.Operation), setName, exp))

	if exprsStr != "" {
		sb.WriteString(" ")
		sb.WriteString(exprsStr)
	}

	if srcRegData, ok := ctx.reg.Get(regID(dyn.SrcRegData)); ok {
		if exprData := srcRegData.HumanExpr; exprData != "" {
			sb.WriteString(fmt.Sprintf(" : %s", exprData))
		}
	}

	sb.WriteString(" }")

	return simpleIR(sb.String()), nil
}

func (b *dynsetEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	dyn := b.dynset
	srcRegKey, ok := ctx.reg.Get(regID(dyn.SrcRegKey))
	if !ok || srcRegKey.Data == nil {
		return nil, errors.Errorf("%T statement has no key expression", dyn)
	}
	exp := srcRegKey.Data
	if dyn.Timeout != 0 {
		exp = map[string]interface{}{
			"elem": struct {
				Val     any           `val:"json"`
				Timeout time.Duration `timeout:"json"`
			}{
				Val:     exp,
				Timeout: dyn.Timeout,
			},
		}
	}
	setName := fmt.Sprintf(`@%s`, dyn.SetName)
	srcRegData, ok := ctx.reg.Get(regID(dyn.SrcRegData))

	if ok && srcRegData.Data != nil {
		exp = map[string]interface{}{
			"map": struct {
				Op   string `json:"op"`
				Elem any    `json:"elem"`
				Data any    `json:"data"`
				Map  string `json:"map"`
			}{
				Op:   DynSetOP(dyn.Operation).String(),
				Elem: exp,
				Data: srcRegData.Data,
				Map:  setName,
			},
		}
		return json.Marshal(exp)
	}
	exp = map[string]interface{}{
		"set": struct {
			Op   string     `json:"op"`
			Elem any        `json:"elem"`
			Set  string     `json:"set"`
			Stmt []expr.Any `json:"stmt,omitempty"`
		}{
			Op:   DynSetOP(dyn.Operation).String(),
			Elem: exp,
			Set:  setName,
			Stmt: dyn.Exprs,
		},
	}
	return json.Marshal(exp)
}

type DynSetOP uint32

const (
	DynSetOPAdd    DynSetOP = unix.NFT_DYNSET_OP_ADD
	DynSetOPUpdate DynSetOP = unix.NFT_DYNSET_OP_UPDATE
	DynSetOPDelete DynSetOP = iota
)

func (d DynSetOP) String() string {
	switch d {
	case DynSetOPAdd:
		return "add"
	case DynSetOPUpdate:
		return "update"
	case DynSetOPDelete:
		return "delete"
	}
	return "unknown"
}
