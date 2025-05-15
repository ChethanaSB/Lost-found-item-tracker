from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Download NLTK resources
try:
    nltk.download('punkt')
    nltk.download('stopwords')
except Exception as e:
    logger.warning(f"Failed to download NLTK resources: {str(e)}")

# Initialize stop words
try:
    stop_words = set(stopwords.words('english'))
except Exception as e:
    logger.warning(f"Failed to load stopwords: {str(e)}")
    stop_words = set()

def preprocess_text(text):
    """Preprocess text by removing special characters, converting to lowercase, and removing stop words."""
    # Convert to lowercase and remove special characters
    text = re.sub(r'[^\w\s]', '', text.lower())
    
    # Tokenize and remove stop words
    word_tokens = word_tokenize(text)
    filtered_text = [word for word in word_tokens if word not in stop_words]
    
    return ' '.join(filtered_text)

def calculate_similarity(text1, text2):
    """Calculate similarity between two text descriptions using TF-IDF and cosine similarity."""
    try:
        # Preprocess texts
        processed_text1 = preprocess_text(text1)
        processed_text2 = preprocess_text(text2)
        
        # Create TF-IDF vectors
        vectorizer = TfidfVectorizer()
        tfidf_matrix = vectorizer.fit_transform([processed_text1, processed_text2])
        
        # Calculate cosine similarity
        similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
        
        logger.info(f"Similarity score: {similarity}")
        return similarity
    
    except Exception as e:
        logger.error(f"Error calculating similarity: {str(e)}")
        return 0.0

# Alternative implementation using spaCy (uncomment to use)
"""
import spacy

# Load spaCy model
try:
    nlp = spacy.load('en_core_web_md')
except Exception as e:
    logger.error(f"Failed to load spaCy model: {str(e)}")
    # Fallback to small model
    try:
        nlp = spacy.load('en_core_web_sm')
    except:
        logger.error("Failed to load any spaCy model")
        nlp = None

def calculate_similarity_spacy(text1, text2):
    if nlp is None:
        return calculate_similarity(text1, text2)  # Fallback to TF-IDF
    
    try:
        # Process texts with spaCy
        doc1 = nlp(text1)
        doc2 = nlp(text2)
        
        # Calculate similarity
        similarity = doc1.similarity(doc2)
        
        logger.info(f"Similarity score (spaCy): {similarity}")
        return similarity
    
    except Exception as e:
        logger.error(f"Error calculating similarity with spaCy: {str(e)}")
        return calculate_similarity(text1, text2)  # Fallback to TF-IDF
"""
