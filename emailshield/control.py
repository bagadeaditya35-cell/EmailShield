"""In-process control flag: the API sets it, the engine's main loop watches it, so 'Stop EmailShield engine' works without signals."""
import threading

STOP = threading.Event()
