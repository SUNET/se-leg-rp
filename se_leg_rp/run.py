# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from se_leg_rp.app import se_leg_rp_init_app

name = 'se_leg_rp'
app = se_leg_rp_init_app(name, {})


if __name__ == '__main__':
    app.logger.info('Starting {} app...'.format(name))
    app.run()
