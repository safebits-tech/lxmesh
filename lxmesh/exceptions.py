__all__ = ['ApplicationError']


class ApplicationError(Exception):
    @property
    def message_sentence(self) -> str:
        message = str(self)
        return message[0].upper() + message[1:] + "."
