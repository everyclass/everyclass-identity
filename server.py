import gc

from everyclass.identity import create_app

app = create_app()

# disable gc and freeze
gc.set_threshold(0)  # 700, 10, 10 as default
gc.freeze()

if __name__ == '__main__':
    print("You should not run this file. Instead, run `uwsgi --ini deploy/uwsgi-local.ini` for consistent behaviour.")
