import sys
import signal
import time
import yaml

from hpotter.logger import logger
from hpotter.plugins.ListenThread import ListenThread
from hpotter.db import db

# https://stackoverflow.com/questions/18499497/how-to-process-sigterm-signal-gracefully
class GracefulKiller:
    kill_now = False
    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        logger.info('In exit_gracefully')
        self.kill_now = True

class HP():
    def __init__(self):
        self.listen_threads = []

    def startup(self):
        db.open()

        with open('plugins.yml') as f:
            for config in yaml.safe_load_all(f):
                lt = ListenThread(config)
                self.listen_threads.append(lt)
                lt.start()

    def shutdown(self):
        db.close()

        for lt in self.listen_threads:
            if lt.is_alive():
                lt.shutdown()

if "__main__" == __name__:
    hp = HP()
    hp.startup()

    killer = GracefulKiller()
    while not killer.kill_now:
        time.sleep(5)

    hp.shutdown()
