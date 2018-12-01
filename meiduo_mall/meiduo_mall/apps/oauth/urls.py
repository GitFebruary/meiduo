from django.conf.urls import url
from oauth import views

urlpatterns = [
    url(r'^qq/authorization/$', views.OauthLoginViewQQ.as_view()),
    url(r'^qq/user/$', views.OauthView.as_view()),
    url(r'^wb/authorization/$', views.OauthLoginViewWB.as_view()),
    url(r'^wb/user/$', views.OauthView.as_view())
]