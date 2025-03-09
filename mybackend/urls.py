from django.urls import path
from api.views import FeedbackView

from api.views import SignUpView
from api.views import LoginView
from api.views import AlertsView,  FeedbackView
from api.views import ChatHandlerView, AlertStreamView, AlertDetailView
urlpatterns = [
    
    path('api/register/', SignUpView.as_view(), name='register'),
    path('api/token/', LoginView.as_view(), name='login'),
    path('api/alerts/', AlertsView.as_view(), name='alert-list'),
    path('api/chat/', ChatHandlerView.as_view(), name='chat_handler'),
    path('api/alerts/stream/', AlertStreamView.as_view(), name='alert_stream'),
    path('api/alerts/<str:alert_id>/', AlertDetailView.as_view(), name='alert_detail'),
    path('api/feedback/', FeedbackView.as_view(), name='submit-feedback'),
   
]
   
