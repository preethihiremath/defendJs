export const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };
  
  export const validatePassword = (password) => {
    // Enhanced complexity requirements (at least 12 characters, mix of uppercase, lowercase, numbers, and symbols)
    const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{12,}$/;
    return passwordRegex.test(password);
  };
  
  export const validatePhoneNumber = (phoneNumber) => {
    // International phone number validation using libphonenumber-js (install with `npm install libphonenumber-js`)
    const pnf = require('libphonenumber-js');
    try {
      const parsedNumber = pnf.parseAndValidate(phoneNumber);
      return parsedNumber.isValid();
    } catch (error) {
      return false;
    }
  };
  
  export const validateDate = (date, format = 'YYYY-MM-DD') => {
    // Flexible date format validation using Moment.js (install with `npm install moment`)
    const moment = require('moment');
    return moment(date, format, true).isValid();
  };
  
  export const validateNumericValue = (value, min = null, max = null) => {
    // Flexible numeric validation with optional min/max checks
    if (isNaN(value)) {
      return false;
    }
  
    const number = parseFloat(value); // Ensure numeric type
    return (min === null || number >= min) && (max === null || number <= max);
  };
  
  export const validateURL = (url) => {
    // Enhanced URL validation using a regular expression (https://gist.github.com/damieng/3888768)
    const urlRegex = /^(http|https):\/\/\S+$/;
    return urlRegex.test(url);
  };
  
  export const validateIPAddress = (ipAddress) => {
    // IP address validation using a regular expression (https://stackoverflow.com/a/7863880)
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    return ipRegex.test(ipAddress);
  };
  
  export const validateBoolean = (value) => {
    return typeof value === 'boolean';
  };
  
  export const validateFileUpload = (file, allowedTypes = [], maxSize = null) => {
    // File upload validation with optional allowed types and size limit
    if (!file || !file.type || !file.size) {
      return false;
    }
  
    const fileType = file.type.toLowerCase();
    const isAllowedType = allowedTypes.length === 0 || allowedTypes.includes(fileType);
    const isWithinSizeLimit = maxSize === null || file.size <= maxSize;
  
    return isAllowedType && isWithinSizeLimit;
  };
  
  export const validateText = (text, minLength = null, maxLength = null, allowedChars = null) => {
    // Flexible text validation with optional min/max length and allowed character restrictions
    if (typeof text !== 'string') {
      return false;
    }
  
    const textLength = text.length;
    const isValidLength = (minLength === null || textLength >= minLength) && (maxLength === null || textLength <= maxLength);
    const hasAllowedChars = allowedChars === null || new RegExp(`[^${allowedChars}]`).test(text) === false;
  
    return isValidLength && hasAllowedChars;
  };
  