function sample(input) { let run = eval; function change() { run = other; } run(input); }
