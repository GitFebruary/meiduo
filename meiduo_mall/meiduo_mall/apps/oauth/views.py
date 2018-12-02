from django_filters.conf import settings
from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from QQLoginTool.QQtool import OAuthQQ
from rest_framework_jwt.settings import api_settings
from itsdangerous import TimedJSONWebSignatureSerializer as TJS
from oauth.models import OAuthQQUser, OAuthSinaUser
from oauth.serializers import OauthSerializers, OauthSerializersWB
# from settings.dev import QQ_CLIENT_ID, QQ_CLIENT_SECRET, QQ_REDIRECT_URI
from django.conf import settings

from users.utils import merge_cart_cookie_to_redis

from .WBtool import OAuthWB

class OauthLoginViewQQ(APIView):
    """
        构造qq登录的跳转链接

    """
    def get(self, request):

        # 获取前端发送的参数
        state = request.query_params.get('next', None)

        # 前端如果没有传递需要手动写入
        if state is None:
            state = '/'

        # 初始化QuathQQ对象
        qq = OAuthQQ(client_id=settings.QQ_CLIENT_ID, client_secret=settings.QQ_CLIENT_SECRET, redirect_uri=settings.QQ_REDIRECT_URI, state=state)

        # 构造qq登录页面的跳转链接
        login_url = qq.get_qq_url()

        # 返回结果
        return Response(
            {
            'login_url': login_url
            }
        )


class OauthLoginViewWB(APIView):
    """
        构造微博登录的跳转链接

    """
    def get(self, request):

        # 获取前端发送的next参数/防止csrf攻击
        state = request.query_params.get('next', None)

        # 前端如果没有传递需要手动写入
        if state is None:
            state = '/'

        # 初始化QuathWB对象
        wb = OAuthWB(client_id=settings.WB_CLIENT_ID, client_secret=settings.WB_CLIENT_SECRET, redirect_uri=settings.WB_REDIRECT_URI, state=state)

        # 构造wb登录页面的跳转链接
        login_url = wb.get_wb_url()

        # 返回结果
        return Response(
            {
            'login_url': login_url
            }
        )


class OauthView(CreateAPIView):

    serializer_class = OauthSerializers

    def get(self, request):
        """
            获取openid
            思路分析:
            前端:
            1. 用户扫码成功之后,qq服务器会引导用户跳转到美多页面
            2. 前端通过js代码获取路径中的code(授权码)值, 并携带code值向后端发送请求
            后端:
            3. 获取code值,生成Access Token
        """
        # 获取code值
        AuthCode = request.query_params.get('code', None)

        # 判断AuthCode值是否存在
        if not AuthCode:
            return Response({'message': '缺少code值'}, status=400)

        # 通过code值获取token, 实例QQ对象
        qq = OAuthQQ(client_id=settings.QQ_CLIENT_ID, client_secret=settings.QQ_CLIENT_SECRET, redirect_uri=settings.QQ_REDIRECT_URI, state='/')

        # 调用get_access_token方法获取token值
        access_token = qq.get_access_token(code=AuthCode)

        # 通过access_token获取openid
        openid = qq.get_open_id(access_token=access_token)

        # 判断操作
        try:
            # 查询表中是否有数据
            qq_user = OAuthQQUser.objects.get(openid=openid)
        except Exception as e:

            # 将openid进行加密操作,密文返回给前端
            tjs = TJS(settings.SECRET_KEY, 300)

            # 调用加密方法进行加密
            open_id = tjs.dumps({'openid': openid}).decode()

            # 报错,说明没有,跳转到绑定页面(access_token前端接收openid的变量)
            # 因为在绑定的时候需要openid与user一起绑定所以需要传递
            return Response({'access_token': open_id})

        else:
            # 没有报错说明已经绑定过,跳转到首页
            # 获取qq_user中的user对象
            user = qq_user.user
            # 因为是登录操作,所以需要生成token数据发送给前端
            # token加密
            jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)

            # user对象添加属性
            user.token = token

            response = Response(
                {
                    'token':token,
                    'username':user.username,
                    'user_id': user.id

                }
            )
            response = merge_cart_cookie_to_redis(request, response, user)
            return response


    # # 指明序列化器
    # serializer_class = OauthSerializers


class OauthViewWB(CreateAPIView):

    # 绑定access——token
    serializer_class = OauthSerializersWB
    # 获取access——token
    def get(self, request):
        """
            获取openid
            思路分析:
            前端:
            1. 用户扫码成功之后,qq服务器会引导用户跳转到美多页面
            2. 前端通过js代码获取路径中的code(授权码)值, 并携带code值向后端发送请求
            后端:
            3. 获取code值,生成Access Token
        """
        # 获取code值
        AuthCode = request.query_params.get('code', None)
        # 判断AuthCode值是否存在
        if not AuthCode:
            return Response({'message': '缺少code值'}, status=400)

        # 通过code值获取assess_token, 实例QQ对象
        wb = OAuthWB(client_id=settings.WB_CLIENT_ID, client_secret=settings.WB_CLIENT_SECRET, redirect_uri=settings.WB_REDIRECT_URI, state='/')

        # 调用get_access_token方法获取token值
        access_token = wb.get_access_token(code=AuthCode)
        #
        # # 通过access_token获取openid
        # openid = qq.get_open_id(access_token=access_token)

        # 判断操作
        try:
            # 查询表中符合access——token的数据对象
            wb_user = OAuthSinaUser.objects.get(access_token=access_token)
        except Exception as e:

            # 将openid进行加密操作,密文返回给前端
            tjs = TJS(settings.SECRET_KEY, 300)

            # 调用加密方法进行加密
            access_token = tjs.dumps({'access_token': access_token}).decode()

            # 报错,说明没有,跳转到绑定页面(access_token前端接收openid的变量)
            # 因为在绑定的时候需要openid与user一起绑定所以需要传递
            return Response({'access_token': access_token})


        else:
            # 没有报错说明已经绑定过,跳转到首页
            # 获取qq_user中的user对象
            user = wb_user.user
            # 因为是登录操作,所以需要生成token数据发送给前端
            # token加密
            jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)

            # user对象添加属性
            user.token = token

            response = Response(
                {
                    'token':token,
                    'username':user.username,
                    'user_id': user.id

                }
            )
            response = merge_cart_cookie_to_redis(request, response, user)
            return response


    # # 指明序列化器
    # serializer_class = OauthSerializers

