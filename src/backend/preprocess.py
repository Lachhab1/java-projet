from sklearn.base import TransformerMixin

class TextPreprocessor(TransformerMixin):
    def transform(self, X, **transform_params):
        import pandas as pd
        return [str(text).lower() for text in X]

    def fit(self, X, y=None, **fit_params):
        return self

preprocess = TextPreprocessor()