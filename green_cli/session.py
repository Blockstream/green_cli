import logging
import threading

import green_gdk as gdk

from green_cli import context

class Session(gdk.Session):

    def __init__(self, net_params):
        self.current_block_height = None
        self.latest_events = {}
        self.event_cv = threading.Condition()
        super().__init__(net_params)

    def getlatestevent(self, event_type, timeout):
        with self.event_cv:
            timeout = None if timeout < 0 else timeout
            self.event_cv.wait_for(lambda: event_type in self.latest_events, timeout=timeout)
        return self.latest_events.get(event_type, dict())

    def callback_handler(self, event):
        logging.debug("Callback received event: {}".format(event))
        try:
            event_type = event['event']
            event_body = event[event_type]

            if event_type == 'network':
                logging.debug("Setting logged_in to false after network event")
                context.logged_in = False

            if event_type == 'block':
                self.current_block_height = event_body['block_height']
                logging.debug(f"Updated current block height to {self.current_block_height}")

            self.latest_events[event_type] = event_body
            with self.event_cv:
                self.event_cv.notify()

        except Exception as e:
            logging.error("Error processing event: {}".format(str(e)))

        super().callback_handler(event)
