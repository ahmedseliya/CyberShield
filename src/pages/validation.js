// utils/validation.js
export const validationRules = {
  username: {
  regex: /^(?=.*[a-zA-Z])[a-zA-Z0-9_ ]{3,20}$/,
  message: "3-20 chars, must contain a letter, only letters, numbers, spaces, and underscores allowed."
},
  email: {
  regex: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  message: "Enter a valid email address." // Instagram-style
},
  password: {
    regex: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    message: "Min 8 chars with uppercase, lowercase, number, and special character (@$!%*?&)."
  }
};

export const sanitizeInput = (input) => {
  return input
    .toString()
    .replace(/[<>"'`;()]/g, '')
    .replace(/\b(OR|AND|SELECT|INSERT|DELETE|UPDATE|DROP|UNION|EXEC)\b/gi, '')
    .trim()
    .substring(0, 100);
};

export const validateField = (fieldName, value) => {
  const sanitizedValue = sanitizeInput(value);
  
  if (!sanitizedValue) {
    return { isValid: false, message: `${fieldName} is required.` };
  }

  const rule = validationRules[fieldName];
  if (rule && !rule.regex.test(sanitizedValue)) {
    return { isValid: false, message: rule.message };
  }

  return { isValid: true, message: '', value: sanitizedValue };
};