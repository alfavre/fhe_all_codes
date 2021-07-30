// this works on trust for no dupe and no blank!
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq)]
enum ColorPeg {
    Red,
    Green,
    Blue,
    Yellow,
    Beige,
    Orange,
    Black,
    White,
}

#[derive(Debug, PartialEq)]
enum CtrlPeg {
    Red,
    White,
}

#[derive(Debug, PartialEq)]
struct Combinaison {
    code: Vec<ColorPeg>,
}

#[derive(Debug)]
struct Control {
    result: VecDeque<CtrlPeg>,
}

impl Combinaison {
    fn new(
        color_0: ColorPeg,
        color_1: ColorPeg,
        color_2: ColorPeg,
        color_3: ColorPeg,
    ) -> Combinaison {
        Combinaison {
            code: vec![color_0, color_1, color_2, color_3],
        }
    }

    fn compare(&self, other: &Combinaison) -> Control {
        let mut my_result: VecDeque<CtrlPeg> = VecDeque::new();

        //whites
        for color_peg in &self.code {
            if other.code.iter().any(|color| color == color_peg) {
                my_result.push_back(CtrlPeg::White);
            }
        }
        //reds
        for i in 0..4 {
            if self.code[i] == other.code[i] {
                my_result.pop_front();
                my_result.push_back(CtrlPeg::Red);
            }
        }

        Control::new(my_result)
    }
}

impl Control {
    fn new(result: VecDeque<CtrlPeg>) -> Control {
        Control { result: result }
    }
}

fn test() {
    println!("Random tests");
    let my_code = Combinaison::new(
        ColorPeg::Red,
        ColorPeg::Green,
        ColorPeg::Blue,
        ColorPeg::Yellow,
    );
    println!("Here is the code to break: {:?}", my_code);

    let my_first_try = Combinaison::new(
        ColorPeg::Green,
        ColorPeg::Blue,
        ColorPeg::Yellow,
        ColorPeg::Red,
    );
    println!("Here is the first try: {:?}", my_first_try);

    println!(
        "Here is the first compare: {:?}",
        my_code.compare(&my_first_try)
    );

    let my_second_try = Combinaison::new(
        ColorPeg::White,
        ColorPeg::Blue,
        ColorPeg::Black,
        ColorPeg::Beige,
    );
    println!("Here is the second try: {:?}", my_second_try);

    println!(
        "Here is the second compare: {:?}",
        my_code.compare(&my_second_try)
    );

    let my_winning_try = Combinaison::new(
        ColorPeg::Red,
        ColorPeg::Green,
        ColorPeg::Blue,
        ColorPeg::Yellow,
    );
    println!("Here is the winning try: {:?}", my_winning_try);

    println!(
        "Here is the winning compare: {:?}",
        my_code.compare(&my_winning_try)
    );
}

fn main(){

    println!("Oxyded Mastermind!");

    let secret_code = Combinaison::new(
        ColorPeg::Red,
        ColorPeg::Green,
        ColorPeg::Blue,
        ColorPeg::Yellow,
    );


    let player_code = Combinaison::new(
        ColorPeg::Red,
        ColorPeg::Green,
        ColorPeg::Yellow,
        ColorPeg::Blue,
    );

    let now = Instant::now();
    let result = secret_code.compare(&player_code);
    println!("{}", now.elapsed().as_nanos());
    println!("{:?}",result);
}
