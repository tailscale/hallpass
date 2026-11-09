(function() {
  'use strict';

  function updateDurationOptions() {
    const selectedRadio = document.querySelector('input[name="accessType"]:checked');
    if (!selectedRadio) return;

    const maxMs = parseInt(selectedRadio.getAttribute('data-max-ms'), 10);

    const durationSelect = document.getElementById('duration');
    const options = durationSelect.querySelectorAll('option');
    let firstValidOption = null;
    let currentlySelectedValid = false;

    options.forEach(function(option) {
      const optionMs = parseInt(option.getAttribute('data-ms'), 10);

      if (optionMs <= maxMs) {
        option.disabled = false;
        option.style.display = '';
        if (!firstValidOption) {
          firstValidOption = option;
        }
        if (option.selected) {
          currentlySelectedValid = true;
        }
      } else {
        option.disabled = true;
        option.style.display = 'none';
      }
    });

    if (!currentlySelectedValid && firstValidOption) {
      firstValidOption.selected = true;
    }
  }

  const radioButtons = document.querySelectorAll('input[name="accessType"]');
  radioButtons.forEach(function(radio) {
    radio.addEventListener('change', updateDurationOptions);
  });

  updateDurationOptions();
})();
