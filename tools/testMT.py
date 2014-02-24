from threading import Thread
import time,random
from Queue import Queue

queue = Queue(10)

class ProducerThread(Thread):
    def run(self):
        nums = range(5)
        global queue
#        for i in range(0,10):
	while True: 
       	    num = random.choice(nums)
            queue.put(num)
            print "Produced", num
            time.sleep(random.random())


class ConsumerThread(Thread):
    def run(self):
        global queue
#       while not queue.empty():
	while True:  
            num = queue.get()
            queue.task_done()
            print "Consumed", num
            time.sleep(random.random())
	print 'Waiting...'

ProducerThread().start()
ConsumerThread().start()
