import logging
import threading
import time

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s',
                    )

def wait_for_event(e):
    #Wait for the event to be set before doing anything
    logging.debug('wait_for_event() - Wait_for_event starting')
    event_is_set = e.wait()
    logging.debug('wait_for_event() Event set: %s', event_is_set)

def wait_for_event_timeout(e, t):
    #Wait t seconds and then timeout
    while not e.isSet():
        logging.debug('wait_for_event_timeout() - Wait_for_event_timeout starting')
        event_is_set = e.wait(t)
        logging.debug('wait_for_event_timeout() - Event set: %s', event_is_set)
        if event_is_set:
            logging.debug('wait_for_event_timeout() - Processing event')
        else:
            logging.debug('wait_for_event_timeout() - Doing other work')


e = threading.Event()
t1 = threading.Thread(name='Block', target=wait_for_event, args=(e,))
t2 = threading.Thread(name='Non-block', target=wait_for_event_timeout, args=(e, 0.5))
logging.debug('Starting thread (1)')
t1.start()

logging.debug('Starting thread (2)')
t2.start()

logging.debug('Waiting before calling Event.set()')
time.sleep(10)
e.set()
logging.debug('Event is set')

