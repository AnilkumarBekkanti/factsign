from django.urls import path
from . import views
from .views import SendDocumentView, SignedDocumentView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    

# otp  sending and verification
    path('otp/send/', views.SendOTPView.as_view(), name='send_otp'),
    path('otp/verify/', views.VerifyOTPView.as_view(), name='verify_otp'),


#  post and get the document
    path('document/send/', views.SendDocumentView.as_view(), name='send_document'),    
    path('document/get/<int:document_id>/', views.GetEncryptedDocumentView.as_view(), name='get_document'),

# Get all documnets
    path('documents/decrypted/', views.AllDecryptedDocumentsView.as_view(), name='get_all_documents'),


# track audit logs like document sent to the user, document opened, document signed
    path('assignments/', views.DocumentAssignmentView.as_view(), name='document-assignment'),   
    path('document/opened/<int:document_id>/', views.DocumentOpenedView.as_view(), name='document-opened'),
    path('audit/logs/<int:document_id>/', views.AuditLogListView.as_view(), name='audit-log'),

#  post Signed Document and get signed document
    path('document/<int:document_id>/sign/', SignedDocumentView.as_view(), name='sign1_document'),
    path('signed-document/<int:pk>/', views.GetSignedDocumentView.as_view(), name='get_signed_document'),


]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
