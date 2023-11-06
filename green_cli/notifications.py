import logging
import queue

def notifications(session, timeout=1):
    while True:
        try:
            n = session.notifications.get(block=True, timeout=timeout)
            logging.debug(f'notification: {n}')
            yield n
        except queue.Empty:
            logging.debug("queue.Empty, passing")
            pass
        except KeyboardInterrupt:
            logging.debug("KeyboardInterrupt during listen, returning")
            raise
