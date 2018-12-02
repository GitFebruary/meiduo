from django.conf.urls import url
from oauth import views

urlpatterns = [
    url(r'^qq/authorization/$', views.OauthLoginViewQQ.as_view()),
    url(r'^qq/user/$', views.OauthView.as_view()),
    url(r'^sina/authorization/$', views.OauthLoginViewWB.as_view()),
    url(r'^sina/user/$', views.OauthViewWB.as_view())
]