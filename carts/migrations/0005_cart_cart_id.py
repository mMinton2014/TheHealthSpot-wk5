# Generated by Django 3.1 on 2021-08-07 02:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('carts', '0004_remove_cart_cart_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='cart',
            name='cart_id',
            field=models.CharField(blank=True, max_length=250),
        ),
    ]
