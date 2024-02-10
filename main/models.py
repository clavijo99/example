from django.db import models
from django.utils.translation import gettext_lazy as _



class Configuration(models.Model):
    key = models.CharField(max_length=200)
    value = models.CharField(max_length=200)

    class Meta:
        verbose_name = _("Configuracion")
        verbose_name_plural = _("Configuraciones")

    def __str__(self):
        return self.key