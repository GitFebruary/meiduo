from django.conf.urls import url
from carts import views

urlpatterns = [
    url(r'^cart/$', views.CartsView.as_view()),
    url(r'^cart/selection/$', views.CartsSelectionView.as_view()),
    url(r'^collect/$', views.CollectView.as_view()),
    url(r'^collect/selection/$', views.CartsSelectionView.as_view()),
]