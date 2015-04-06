import thread, time

def counter(myId, count):
    for i in range(count):
        time.sleep(1)
        print '[%s] => %s' % (myId, i)

for i in range(5):
    thread.start_new_thread(counter, (i, 5))

time.sleep(6)
print 'Main thread exiting.'
