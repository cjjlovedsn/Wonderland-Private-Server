import socket, threading, time, sys, os

REMOTE_HOST = sys.argv[1] if len(sys.argv) > 1 else "210.242.243.183"
REMOTE_PORT = 6414
LOCAL_PORT = 6414
LOGDIR = os.path.dirname(os.path.abspath(__file__))
LOG = open(os.path.join(LOGDIR, "mitm_capture.txt"), "a", encoding="utf-8")
lock = threading.Lock()
conn_counter = [0]

def log(cid, dirn, data):
    ts = time.strftime("%H:%M:%S") + ".%03d" % (int(time.time() * 1000) % 1000)
    with lock:
        LOG.write("[%s] conn#%d %s len=%d\n%s\n\n" % (ts, cid, dirn, len(data), data.hex(" ")))
        LOG.flush()

def pipe(cid, src, dst, dirn):
    try:
        while True:
            d = src.recv(65536)
            if not d:
                break
            log(cid, dirn, d)
            dst.sendall(d)
    except Exception as e:
        with lock:
            LOG.write("conn#%d %s closed err=%r\n\n" % (cid, dirn, e))
            LOG.flush()
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass

def handle(client, cid):
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        remote = socket.create_connection((REMOTE_HOST, REMOTE_PORT), timeout=10)
    except Exception as e:
        with lock:
            LOG.write("conn#%d CONNECT to %s:%d FAILED %r\n\n" % (cid, REMOTE_HOST, REMOTE_PORT, e))
            LOG.flush()
        client.close()
        return
    remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    with lock:
        LOG.write("=== conn#%d OPEN -> %s:%d ===\n\n" % (cid, REMOTE_HOST, REMOTE_PORT))
        LOG.flush()
    t1 = threading.Thread(target=pipe, args=(cid, client, remote, "C->S"), daemon=True)
    t2 = threading.Thread(target=pipe, args=(cid, remote, client, "S->C"), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()
    client.close(); remote.close()
    with lock:
        LOG.write("=== conn#%d CLOSED ===\n\n" % cid)
        LOG.flush()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", LOCAL_PORT))
srv.listen(16)
print("MITM proxy 127.0.0.1:%d -> %s:%d, logging to mitm_capture.txt" % (LOCAL_PORT, REMOTE_HOST, REMOTE_PORT), flush=True)
while True:
    c, _ = srv.accept()
    with lock:
        conn_counter[0] += 1
        cid = conn_counter[0]
    threading.Thread(target=handle, args=(c, cid), daemon=True).start()
