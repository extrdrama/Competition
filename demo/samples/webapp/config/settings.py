'''应用配置（演示样本，凭据均为伪造值）。'''

DEBUG = False
ALLOWED_HOSTS = ["api.internal-demo.example.com"]

# 硬编码的数据源与第三方密钥（典型的"不该出现"写法）
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "production",
        "USER": "app_rw",
        "PASSWORD": "Pr0d_xJYLv619qcS6",
        "HOST": "10.20.30.41",
        "PORT": 3306,
    }
}

DJANGO_SECRET_KEY = "2IQQtnRIkapncp3NyyN0opg5sLiEUfDmiXdrC0xaEuwzebZqPj"

# 支付与消息推送
STRIPE_SECRET_KEY = "sk_live_ykzPIQIyQbrtZS62U4r9nb43"
SLACK_BOT_TOKEN = "xoxb-999055828342-508792288728-sPKtieyiUeCyncIFubBqsJbS"
