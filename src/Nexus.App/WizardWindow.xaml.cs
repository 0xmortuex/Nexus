using System.Windows;
using Nexus.App.ViewModels;

namespace Nexus.App;

public partial class WizardWindow : Window
{
    public WizardWindow(WizardViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.CloseRequested += Close;
    }
}
