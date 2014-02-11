import datetime
import delorean
dt = datetime.datetime.utcnow()
print delorean.Delorean(dt, timezone="UTC").epoch()

