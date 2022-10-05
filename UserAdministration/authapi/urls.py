# from django.urls import path

from . import views

# urlpatterns = [
#     # path('', views.index, name='index'),
# ]

from django.urls import path
from knox import views as knox_views
from authapi.views import *

# app_name = 'core'

urlpatterns = [
    # path('create/', CreateUserView.as_view(), name="create"),
    # path('profile/', ManageUserView.as_view(), name='profile'),
    path('login/', LoginApi.as_view(), name='knox_login'),
    path('logout/', knox_views.LogoutView.as_view(), name='knox_logout'),
    path('logoutall/', knox_views.LogoutAllView.as_view(), name='knox_logoutall'),
    path("create_role/",CreateRole.as_view()),
    path('edit_role/',EditRole.as_view()),
    path('role_list/',RoleList),
    path('create_rights/',CreateRights.as_view()),
    path('edit_rights/',EditRights.as_view()),
    path('rights_list/',RightsList),
    path('create_user/',CreateUser.as_view()),
    path('edit_user/',EditUser.as_view()),
    path('user_list/',UserList),
    path("delete_user/",DeleteUser.as_view()),
    path('delete_role/',DeleteRole.as_view()),
    path('delete_rights/',DeleteRights.as_view())
    
]



