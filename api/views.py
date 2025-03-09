from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import FeedbackSerializer, SignUpSerializer, LoginSerializer

# ===========================
# Feedback Views
# ===========================
from django.http import JsonResponse
from django.views import View

from .mongo_utils import get_all_parsed_alerts, submit_feedback,get_parsed_alert


from . import mongo_utils



from rest_framework import status
  # Assuming you have utility functions for MongoDB


from django.core.exceptions import ValidationError


class AlertsView(View):
    def get(self, request):
        """
        Get a list of alerts with parsed message, suggestions, and affected transactions, paginated.
        """
        try:
            limit = int(request.GET.get('limit', 10))  # Default to 3 alerts per request
            skip = int(request.GET.get('skip', 0))    # Default to starting from the first alert
            alerts = get_all_parsed_alerts(limit, skip)
            return JsonResponse({'status': 'success', 'data': alerts}, status=200)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

class AlertDetailView(View):
    def get(self, request, alert_id):
        """
        Get a specific alert with its parsed message, suggestions, and affected transactions.
        """
        try:
            alert = get_parsed_alert(alert_id)
            if alert:
                return JsonResponse({'status': 'success', 'data': alert}, status=200)
            return JsonResponse({'status': 'error', 'message': 'Alert not found'}, status=404)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)




from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import exceptions

# Optional: Custom authentication to ignore failed auth attempts
class OptionalAuthentication:
    def authenticate(self, request):
        try:
            # Try to authenticate but don't raise errors
            return None  # Bypass authentication checks
        except exceptions.AuthenticationFailed:
            return None  # Silently ignore auth failures

# views.py
class FeedbackView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []  # Disable all authentication for this view

    def post(self, request):
        """Submit feedback with optional user association."""
        try:
            feedback_data = request.data.copy()
            
            # Associate user only if they're properly authenticated
            if request.user.is_authenticated:
                feedback_data['user_id'] = str(request.user.id)

            serializer = FeedbackSerializer(data=feedback_data)
            
            if not serializer.is_valid():
                return Response(
                    {"error": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            feedback_id = submit_feedback(serializer.validated_data)
            
            if not feedback_id:
                return Response(
                    {"error": "Failed to save feedback"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {"message": "Feedback submitted", "id": feedback_id},
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# ===========================
# Authentication Views
# ===========================

class SignUpView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import logging

logger = logging.getLogger(__name__)

class LoginView(APIView):
    def post(self, request, *args, **kwargs):
        logger.info(f"Received login request with data: {request.data}")
        
        serializer = LoginSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            logger.error(f"Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)

        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }, status=status.HTTP_200_OK)




## views.py
from django.http import JsonResponse, StreamingHttpResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .mongo_utils import get_mongo_db, rag_pipeline
import time
import json
import logging

logger = logging.getLogger(__name__)



from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import json
import logging
from .mongo_utils import rag_pipeline  # Import the RAG pipeline function

logger = logging.getLogger(__name__)

class ChatHandlerView(View):
    """Handle chat interactions with the SAP monitoring system"""
    
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        """
        Process user message through RAG pipeline and return response
        with related transactions and alerts.
        """
        try:
            # Parse JSON data from the request body
            try:
                data = json.loads(request.body)
                user_message = data.get('message', '')
            except json.JSONDecodeError:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid JSON payload'
                }, status=400)
            
            if not user_message:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Message content is required'
                }, status=400)
            
            # Process with RAG pipeline
            llm_response, transactions = rag_pipeline(user_message)
            
            return JsonResponse({
                'status': 'success',
                'data': {
                    'response': llm_response,
                    'transactions': transactions,
                    'alert': {
                        'title': 'SAP Monitoring Alert',
                        'suggestion': 'Review transaction logs'
                    }
                }
            }, status=200)
            
        except Exception as e:
            logger.error(f"Chat handler error: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': 'Failed to process request'
            }, status=500)
import json
import time
import logging
from bson import json_util  # Import json_util to handle MongoDB-specific types
from django.http import StreamingHttpResponse
from django.views import View


logger = logging.getLogger(__name__)

class AlertStreamView(View):
    """Stream real-time SAP alerts via Server-Sent Events (SSE)"""
    
    def get(self, request, *args, **kwargs):
        """
        Provide continuous stream of SAP alert updates
        """
        def event_stream():
            db = get_mongo_db()
            last_id = None
            
            try:
                while True:
                    # Get new alerts from MongoDB
                    query = {}
                    if last_id:
                        query = {'_id': {'$gt': last_id}}
                    
                    alerts = db.alerts.find(query).sort('_id', 1)
                    
                    for alert in alerts:
                        last_id = alert['_id']
                        # Convert ObjectId to string
                        alert['_id'] = str(alert['_id'])
                        # Use json_util.dumps to handle MongoDB-specific types
                        yield f"data: {json.dumps(alert, default=json_util.default)}\n\n"
                    
                    time.sleep(1)  # Polling interval
                    
            except Exception as e:
                logger.error(f"Alert stream error: {str(e)}")
                yield f"event: error\ndata: {json.dumps({'message': 'Stream interrupted'})}\n\n"

        response = StreamingHttpResponse(
            event_stream(),
            content_type='text/event-stream'
        )
        response['Access-Control-Allow-Origin'] = 'http://localhost:4200'  # Allow CORS
        response['Cache-Control'] = 'no-cache'
        response['Access-Control-Allow-Credentials'] = 'true'
      
        return response