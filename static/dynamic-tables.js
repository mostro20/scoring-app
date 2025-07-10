// initialize filters
let filters = document.querySelectorAll("[data-filter-for]");
for (let i = 0; i < filters.length; i++) {
  initFilter(filters[i]);
}

// initialize col pickers
let pickers = document.querySelectorAll("[data-colpicker-for]");
for (let i = 0; i < pickers.length; i++) {
  initColPicker(pickers[i]);
}

// table filter
function initFilter(filter) {
  let table = document.getElementById(
    filter.getAttribute('data-filter-For')
    );
  let rows = table.tBodies[0].rows;

  filter.addEventListener('input', applyFilter);

  function applyFilter(e) {
    let search = e.target.value;

    // get terms to filter on 
    let terms = search.split(/\s+/)
      .filter((x) => x.length > 0) // skip empty terms
      .map(x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')); // escape regex

    // build pattern/regex
    let pattern = '(' + terms.join('|') + ')';
    let regEx = new RegExp(pattern, 'gi');

    // apply to all rows
    for (let i = 0; i < rows.length; i++) {
      let row = rows[i];
      let match = row.textContent.match(regEx);
      row.classList.toggle(
        'hide-row',
        match == null || match.length < terms.length
      );
    }
  }
}

// table colpicker
function initColPicker(picker) {

  // get our table
  let table = document.getElementById(
    picker.getAttribute('data-colpicker-for')
  );

  // create drop-down list
  let colList = document.createElement('ul');
  colList.classList.add('dropdown-menu');
  picker.appendChild(colList);

  // populate drop-down list
  let columns = table.tHead.children[0].children;
  let html = "";
  for (let i = 0; i < columns.length; i++) {
    let header = columns[i].textContent.trim();
    if (header.length) {
      html += `<li><label><input type="checkbox" data-index="${i}" checked="true"> ${header}</label></li>`
    }
  }
  colList.innerHTML = html;

  // persist layout
  if (table.id && localStorage) {

    // save layout when closing
    window.addEventListener("beforeunload", e => {
      let hidden = [];
      let unchecked = colList.querySelectorAll("input[type=checkbox]:not(:checked)");
      for (let i = 0; i < unchecked.length; i++) {
        hidden.push(unchecked[i].parentElement.textContent.trim());
      }
      localStorage.setItem("col-picker-" + table.id, JSON.stringify(hidden));
    });

    // restore when loading
    let hidden = localStorage.getItem("col-picker-" + table.id);
    if (hidden) {
      JSON.parse(hidden).forEach(hdr => {
        for (let i = 0; i < colList.children.length; i++) {
          let col = colList.children[i];
          if (col.textContent.trim() == hdr) {
            let checkbox = col.querySelector("input[type=checkbox]");
            checkbox.checked = false;
            showColumn(table, checkbox);
            break;
          }
        }
      })
    }
  }

  // add event handler
  colList.addEventListener("click", e => {
    let checkbox = e.target;
    if (checkbox.tagName == "INPUT") {
      showColumn(table, checkbox);
    }
  });

  // show/hide column
  function showColumn(table, checkbox) {

    // get parameters
    let show = checkbox.checked;
    let index = parseInt(checkbox.getAttribute("data-index"));

    // hide/show header cells
    let columns = table.tHead.children[0].children;
    columns[index].classList.toggle("hide-cell", !show);

    // hide/show body cells
    let rows = table.tBodies[0].rows;
    for (let i = 0; i < rows.length; i++) {
      rows[i].children[index].classList.toggle("hide-cell", !show);
    }
  }
}