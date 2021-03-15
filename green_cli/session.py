import logging

import greenaddress as gdk

from green_cli import context

class Session(gdk.Session):

    def __init__(self, net_params):
        super().__init__(net_params)
        self.current_block_height = None

    def callback_handler(self, event):
        logging.debug("Callback received event: {}".format(event))
        try:
            if event['event'] == 'network' and event['network'].get('login_required', False):
                logging.debug("Setting logged_in to false after network event")
                context.logged_in = False

            if event['event'] == 'block':
                self.current_block_height = event['block']['block_height']
                logging.debug(f"Updated current block height to {self.current_block_height}")
        except Exception as e:
            logging.error("Error processing event: {}".format(str(e)))

        super().callback_handler(event)
