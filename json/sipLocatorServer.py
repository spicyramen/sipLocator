import sipLocatorConfig
import socket,sys,logging,traceback,os
from Queue import Queue #Queue encapsulates the behaviour of Condition, wait(), notify(), acquire() etc.
from threading import Thread


# Process SipMessages in Json Format
class SipMsgProducerThread(Thread):
    def run(self):
        try:
            global sipMsgQueue
            sipMsgQueue.put(sipMsg)
            logging.info("Add sipMsg for further processing")
        except Exception,e:
            logging.error('SipMsgProducerThread() Exception found' + str(e))  
            print traceback.format_exc()
            print e  

# Consume SipMessages in Json Format
class SipMsgConsumerThread(Thread):
    def run(self):
        try:
            global sipMsgQueue
            while not sipMsgQueue.empty():
                sipMsg = sipMsgQueue.get()
                sipMsgQueue.task_done()
            logging.info('Finalized processing messages')    
        except Exception,e:
            logging.error('SipMsgProducerThread() Exception found' + str(e))
            print traceback.format_exc()
            print e

def collectSipMsgs():
    print 'TODO'

# Main function
#@profile
def main():
    try:
        if not os.path.exists('logs'):
            os.makedirs('logs')
    except OSError:
        pass
    logging.basicConfig(filename='logs/sipLocatorServer.log', level=logging.INFO, format='%(asctime)s.%(msecs).03d (%(threadName)s) %(message)s', datefmt='%m/%d/%Y %I:%M:%S')   
    logging.info("-----------------------------------------------Initializing sipLocator server-----------------------------------------------")
    print "-----------------------------------------------Initializing sipLocator server-----------------------------------------------"
    try:
        collectSipMsgs()
    except KeyboardInterrupt:
        logging.info ("sipLocator server stopping....")
        try:
            sys.stdout.close()
        except:
            pass
        try:
            sys.stderr.close()
        except:
            pass
    except Exception,e:
        logging.error("Exception found " + str(e))
    except (IOError, OSError):
       pass
        
if __name__ == '__main__':
    main()