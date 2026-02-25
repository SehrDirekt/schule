document.addEventListener('DOMContentLoaded', () => {
  const rows = document.querySelectorAll('.patient-row');
  const card = document.getElementById('patient-card');

  if (!rows.length || !card) {
    return;
  }

  const fields = ['name', 'geburtsdatum', 'geschlecht', 'krankenkasse', 'versicherungsnr', 'adresse', 'telefon', 'email', 'behandlungen', 'medikamente'];

  rows.forEach((row) => {
    row.addEventListener('click', () => {
      fields.forEach((field) => {
        const target = card.querySelector(`[data-field="${field}"]`);
        if (target) {
          target.textContent = row.dataset[field] || '-';
        }
      });
      rows.forEach((otherRow) => otherRow.classList.remove('active'));
      row.classList.add('active');
      card.classList.remove('hidden');
      card.classList.add('show');
      card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  });
});
