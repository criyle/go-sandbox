// Package container provides pre-forked container environment to
// run programs in isolated Linux namespaces.
//
// # Overview
//
// It creates container within unshared container and communicate
// with host process using unix socket with
// oob for fd / pid and commands encoded by gob.
//
// # Protocol
//
// Host to container communication protocol is single threaded and always initiated by
// the host:
//
// ## ping (alive check)
//
// - send: ping
// - reply: pong
//
// ## conf (set configuration)
//
// - send: conf
// - reply:
//
// ## open (open files in given mode inside container):
//
// - send: []OpenCmd
// - reply: "success", file fds / "error"
//
// ## delete (unlink file / rmdir dir inside container):
//
// - send: path
// - reply: "finished" / "error"
//
// ## reset (clean up container for later use (clear workdir / tmp)):
//
// - send:
// - reply: "success"
//
// ## execve: (execute file inside container):
//
// - send: argv, env, rLimits, fds
// - reply:
// - success: "success", pid
// - failed: "failed"
// - send (success): "init_finished" (as cmd)
// - reply: "finished" / send: "kill" (as cmd)
// - send: "kill" (as cmd) / reply: "finished"
// - reply:
//
// Any socket related error will cause the container exit with all process inside container
package container
