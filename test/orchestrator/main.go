// Command harness-worker is the in-cluster Temporal worker for the escape-the-box
// matrix. It registers the MatrixCellWorkflow and its activities on the
// `escape-cells` task queue and drives the existing breakout-run.sh on the
// ac-matrix KubeVirt guest over SSH — durable execution replacing the one-shot
// breakout.sh orchestration (see test/ORCHESTRATION-PLAN.md).
package main

import (
	"log"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

func main() {
	cfg := loadConfig()

	c, err := client.Dial(client.Options{
		HostPort:  cfg.HostPort,
		Namespace: cfg.Namespace,
	})
	if err != nil {
		log.Fatalf("dial temporal %s (ns %s): %v", cfg.HostPort, cfg.Namespace, err)
	}
	defer c.Close()

	w := worker.New(c, cfg.TaskQueue, worker.Options{})
	w.RegisterWorkflow(MatrixCellWorkflow)
	w.RegisterWorkflow(EscapeMatrixWorkflow)
	w.RegisterActivity(&Activities{Cfg: cfg})

	log.Printf("harness-worker up: temporal=%s ns=%s queue=%s substrate=%s vm=%s/%s pod=%s/%s",
		cfg.HostPort, cfg.Namespace, cfg.TaskQueue, cfg.DefaultSubstrate,
		cfg.VMNamespace, cfg.VMName, cfg.PodNamespace, cfg.PodSelector)
	if err := w.Run(worker.InterruptCh()); err != nil {
		log.Fatalf("worker run: %v", err)
	}
}
