import os
from oaps4.libs.config import config
config.set_config_dir(
    os.path.join(
        os.path.dirname(__file__),
        "..", "..", "tests", "config",
        ),
    )
